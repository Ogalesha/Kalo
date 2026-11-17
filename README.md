# Kalo

Kalo is a Bluetooth file-transfer app for Linux. The name comes from Albanian:
**kalo** means **to pass** — files pass from one device to another.

The current release is an Ubuntu-focused Phase 0 implementation built with Rust
and [iced](https://iced.rs/). It sends files over Bluetooth OPP/OBEX, receives
incoming pushes into the user's Downloads folder, and exposes the same
operations through a small CLI.

## Features

- Desktop UI with paired-device selection, send progress, live incoming
  transfers, receiver status and an activity log.
- Outgoing OPP/OBEX transfers with explicit cancel and a stall watchdog.
- Incoming OBEX agent that stages, validates and moves files into the XDG
  Downloads directory.
- Safe handling of untrusted remote filenames.
- CLI commands for adapters, discovery, pairing, diagnostics and transfers.
- Self-contained Ubuntu `.deb` build; no background daemon to enable.

## Platform support

| Platform | Status |
| --- | --- |
| Ubuntu | Supported: build the native `.deb` with `packaging/ubuntu/build-deb.sh` |
| Arch Linux | Planned: the Linux backend (BlueZ, obexd, D-Bus) can be reused; packaging and AUR metadata are still missing |
| Windows | Planned: requires a separate Bluetooth/OBEX backend because the current code depends on BlueZ, obexd and D-Bus |

See [TODO.md](TODO.md) for the platform roadmap and other outstanding work.

## Requirements

Runtime, on Ubuntu:

```sh
sudo apt install bluez bluez-obexd
```

Kalo talks to the system bus (`org.bluez`) and the session bus
(`org.bluez.obex`). The file picker uses the XDG desktop portal, which is
installed by default on Ubuntu desktop.

To build from source you also need a recent Rust toolchain (edition 2024;
Rust 1.98 or newer is known to work) and the usual Linux GUI build
dependencies. The release package recommends `libvulkan1`; iced can fall back
to software rendering, but a working GPU driver gives the best experience.

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

## Build and run

```sh
cargo build --release
./target/release/kalo        # opens the UI
```

Run the UI explicitly with `kalo ui`.

## Usage

1. Pair the other device in your system Bluetooth settings, or use the CLI
   (see below).
2. Open Kalo and select the device under **Device**.
3. Choose a file and press **Send to …**.
4. Incoming files appear under **Incoming** and are saved to the XDG Downloads
   directory (normally `~/Downloads`).

If the receiver reports that the OBEX agent slot is taken, another OBEX agent
(such as Blueman's TransferService) owns it. Disable that agent or stop
`blueman-applet`; Kalo retries registration automatically.

## CLI

```text
kalo                         Open the desktop UI
kalo ui                      Open the desktop UI
kalo adapters                List Bluetooth adapters and their state
kalo connectable [on|off]    Show or set adapter connectable state
kalo devices [--discovery N] List known devices, optionally after discovery
kalo pair <MAC>              Pair with a device
kalo agent-check             Check whether the OBEX agent slot is free
kalo send <MAC> <FILE>       Send a file via Bluetooth OPP
kalo receive                 Run the receiver in the foreground
```

Examples:

```sh
kalo devices --discovery 15
kalo pair AA:BB:CC:DD:EE:FF
kalo send AA:BB:CC:DD:EE:FF ~/Documents/report.pdf
```

## How it works

- **Outgoing:** Kalo creates an OBEX session through obexd, pushes the file over
  OPP, streams progress to the UI/CLI, supports cancellation and fails safely
  when a transfer stalls.
- **Incoming:** Kalo registers an OBEX agent. Authorized pushes are written to
  a staging directory, checked, then moved atomically into Downloads. Partial
  transfers are preserved for manual recovery.
- **Events:** background work publishes typed events to a single bus consumed by
  the UI or the CLI, keeping progress rendering consistent between both.

## Limitations

- **Incoming authorization is accept-all** in this Phase 0 release. Do not run
  the receiver on an untrusted network until a trust store and per-device
  authorization are implemented.
- Linux only for now. Windows support needs a different transport backend.
- Only one OBEX agent can own the agent slot at a time.
- The current `.deb` targets the machine it was built on; cross-release glibc
  compatibility is not guaranteed.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

The codebase is split into `bluez` (system bus), `obex` (outgoing transfers),
`agent` (incoming OBEX agent), `events` (shared event bus), `sanitize`
(untrusted filename safety), `paths` (XDG locations) and `app` (iced UI).

## License

MIT. See [LICENSE](LICENSE).
