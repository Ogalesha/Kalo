# Kalo

Kalo is a Bluetooth file-transfer app for Linux and Windows. The name comes
from Albanian: **kalo** means **to pass** — files pass from one device to
another.

The current release is a Phase 0 implementation built with Rust and
[iced](https://iced.rs/). It sends files over Bluetooth OPP/OBEX, receives
incoming pushes into the user's Downloads folder, and exposes the same
operations through a small CLI. Linux uses BlueZ and obexd; Windows uses WinRT
RFCOMM with a built-in OBEX engine. The Windows backend is **experimental** and
has not yet been validated on Windows hardware.

## Features

- Desktop UI with paired-device selection, send progress, live incoming
  transfers, receiver status and an activity log.
- Outgoing OPP/OBEX transfers with explicit cancel (including during connection
  setup) and a stall watchdog.
- Linux receiver supervision: automatic agent re-registration after obexd or
  session-bus restarts, plus periodic recovery of abandoned staging files.
- Incoming pushes are staged, validated and moved into the Downloads folder.
  Partial files are preserved on errors, cancellation and stalled transfers.
- Safe handling of untrusted remote filenames.
- CLI commands for adapters, discovery, pairing, diagnostics and transfers.
- A native Windows backend with the same UI, CLI and event contract as Linux.
- Self-contained Ubuntu `.deb` and Arch Linux `kalo-git` package builds; no
  background daemon to enable on Linux. Windows packaging is still pending.

## Platform support

| Platform | Status |
| --- | --- |
| Ubuntu | Supported: build the native `.deb` with `packaging/ubuntu/build-deb.sh` |
| Arch Linux | Supported: build `kalo-git` with `packaging/arch/PKGBUILD` (AUR publication pending) |
| Windows | Experimental: native WinRT RFCOMM/OBEX backend. Builds, but has not been tested on Windows hardware yet; packaging is pending |

See [TODO.md](TODO.md) for the platform roadmap and other outstanding work.

## Requirements

Runtime, on Ubuntu:

```sh
sudo apt install bluez bluez-obexd
```

On Arch Linux:

```sh
sudo pacman -S bluez bluez-obexd
```

On Linux, Kalo talks to the system bus (`org.bluez`) and the session bus
(`org.bluez.obex`). The file picker uses the XDG desktop portal, which is
installed by default on Ubuntu desktop; on Arch, install
`xdg-desktop-portal-gtk` (or another portal backend).

On Windows, runtime requirements are Windows 10 or 11 and a working Bluetooth
adapter. Kalo uses WinRT directly, so BlueZ, obexd and D-Bus are not needed.

To build from source you also need a recent Rust toolchain (edition 2024;
Rust 1.98 or newer is known to work) and the usual GUI build dependencies. On
Arch, `base-devel`, `rust` and `cargo` are enough. On Windows, use the MSVC
toolchain with Visual Studio Build Tools and the Windows SDK. The release
packages recommend Vulkan; iced can fall back to software rendering, but a
working GPU driver gives the best experience.

## Install on Ubuntu

Build the package from a checkout:

```sh
./packaging/ubuntu/build-deb.sh
sudo apt install ./dist/kalo_0.1.0-1_amd64.deb
kalo
```

The `.deb` is built for the architecture and glibc of the machine that builds
it. Build on the oldest Ubuntu release you need to support. See
[packaging/ubuntu/README.md](packaging/ubuntu/README.md) for packaging details.

Remove Kalo with:

```sh
sudo apt remove kalo
```

## Install on Arch Linux

The Arch package builds the current `main` branch as `kalo-git`:

```sh
sudo pacman -S --needed base-devel git rust cargo
cd packaging/arch
makepkg -si
kalo
```

The package declares BlueZ, obexd and the required GUI libraries, and installs
the same desktop entry, icon and manual page as the Ubuntu build. See
[packaging/arch/README.md](packaging/arch/README.md) for details. The package is
not published to the AUR yet.

## Build and run

On Linux:

```sh
cargo build --release
./target/release/kalo        # opens the UI
```

On Windows (experimental, untested on hardware):

```powershell
cargo build --release
.\target\release\kalo.exe    # opens the UI
```

Run the UI explicitly with `kalo ui`.

## Usage

1. Pair the other device in your system Bluetooth settings, or use the CLI
   (see below).
2. Open Kalo and select the device under **Device**.
3. Choose a file and press **Send to …**.
4. Incoming files appear under **Incoming** and are saved to the Downloads
   folder (XDG on Linux, normally `~/Downloads`; the Known Folder on Windows).

On Linux, if the receiver reports that the OBEX agent slot is taken, another
OBEX agent (such as Blueman's TransferService) owns it. Disable that agent or
stop `blueman-applet`; Kalo retries registration automatically. On Windows the
receiver advertises the OBEX Object Push RFCOMM service directly and retries if
the radio is off or the service cannot be advertised.

## CLI

```text
kalo                         Open the desktop UI
kalo ui                      Open the desktop UI
kalo adapters                List Bluetooth adapters and their state
kalo connectable [on|off]    Show or set adapter connectable state (show only on Windows)
kalo devices [--discovery N] List known devices, optionally after discovery
kalo pair <MAC>              Pair with a device
kalo agent-check             Check whether the receiver can start
kalo send <MAC> <FILE>       Send a file via Bluetooth OPP
kalo receive                 Run the receiver in the foreground
```

Examples:

```sh
kalo devices --discovery 15
kalo pair AA:BB:CC:DD:EE:FF
kalo send AA:BB:CC:DD:EE:FF path/to/file.pdf
```

## How it works

- **Linux backend:** outgoing transfers use `org.bluez.obex`; incoming pushes go
  through a registered OBEX agent. The receiver is supervised and re-registers
  after obexd or session-bus restarts.
- **Windows backend:** outgoing transfers open an RFCOMM connection to the
  remote Object Push service and drive OBEX with a built-in protocol engine;
  incoming transfers advertise the same service through WinRT and stream each
  push to disk. The backend is experimental and shares the Linux event contract.
- **Transfers:** progress is streamed to the UI/CLI, cancellation interrupts
  connection setup and active transfers, and a watchdog closes stalled sessions.
- **Incoming files:** authorized pushes are written to a staging directory,
  checked, then moved atomically into Downloads. Partial transfers are preserved
  for manual recovery, and stalled or orphaned files are recovered periodically.
- **Supervision:** one shared receiver supervisor handles start retries and
  backend-specific restarts for both the UI and the CLI.
- **Events:** background work publishes typed events to a broadcast bus shared
  by the UI or the CLI, keeping progress rendering consistent between both and
  allowing the UI subscription to be re-created safely.

## Limitations

- **Incoming authorization is accept-all** in this Phase 0 release, on every
  platform. Do not run the receiver on an untrusted network until a trust store
  and per-device authorization are implemented.
- **The Windows backend is experimental and untested on Windows hardware.** It
  compiles and mirrors the Linux behavior, but send, receive, pairing and radio
  edge cases still need validation on real Windows 10/11 machines. There is no
  Windows installer yet.
- On Linux, only one OBEX agent can own the agent slot at a time.
- On Windows, the app must be running to answer pushes; the OPP service is not
  registered as a background task.
- The current `.deb` targets the machine it was built on; cross-release glibc
  compatibility is not guaranteed.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

From Linux, the Windows backend can be type-checked with:

```sh
cargo clippy --target x86_64-pc-windows-msvc --all-targets -- -D warnings
```

The shared code lives in `app` (iced UI), `events` (event bus), `receiver`
(receiver status contract), `platform` (backend facade), `sanitize` (untrusted
filename safety) and `paths` (download locations). Linux adds `bluez` (system
bus), `obex` (outgoing transfers) and `agent` (incoming OBEX agent). Windows
adds `win` (WinRT RFCOMM transport, OPP sender/receiver, device helpers).

## License

MIT. See [LICENSE](LICENSE).
