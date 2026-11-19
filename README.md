<p align="center">
  <img src="docs/kalo.png" alt="Kalo" width="160">
</p>

# Kalo

**Direct Bluetooth file transfers for Linux, macOS, and Windows (experimental).**

Kalo is a native desktop app for sending and receiving files over Bluetooth. Choose a device, pick one file, several files, or a folder, and send it directly — without cables, an account, or a cloud upload. The name comes from Albanian: **kalo means “to pass”**, like a file passing from one device to another.

Built with **Rust** and **[iced](https://iced.rs/)**, Kalo provides a desktop interface and a command-line interface (CLI). Transfers use **Bluetooth Object Push Profile (OPP/OBEX)**, so the other device must support that profile.

> **Project status — early development (Phase 0).** Ubuntu and Arch Linux / Omarchy are the supported Linux targets. macOS is supported for sending and device management; receiving uses the macOS **Bluetooth Sharing** service because Apple provides no public OPP receiver API. A native Windows backend has been implemented, but **has not been validated on real Windows hardware**. GitHub Actions publishes the latest successful Ubuntu `.deb`, Arch Linux package, universal macOS app, and experimental Windows builds.

> **Security model:** Kalo only moves files. It never opens, executes, or remote-controls the peer, and it exposes no remote-control channel in the other direction. Every file is checked against a public SHA-256 malware blocklist before it is sent, and incoming files are scanned again before they reach your save folder. New senders need your approval. Optional Kalo-to-Kalo encryption protects file contents from a passive Bluetooth capture. See [SECURITY.md](SECURITY.md) for the full threat model and hardening details.

## Screenshots

<p align="center">
  <img src="docs/screenshots/kalo-dark.png" width="49%" alt="Kalo in the dark theme">
  <img src="docs/screenshots/kalo-light.png" width="49%" alt="Kalo in the light theme">
</p>

<p align="center"><sub>Dark and light themes, shown with fictional demo data.</sub></p>

## Features

- **Send one file, several files, or a folder:** pick individual files or a whole folder. Folders are scanned off the UI thread, hidden entries and symbolic links are skipped, and files are sent sequentially with one batch progress view.
- **Block known malware:** a bundled baseline plus a public SHA-256 feed blocks malicious files on both send and receive. The feed is served by two endpoints (raw GitHub and jsDelivr), cached append-only so a compromised endpoint cannot silently remove hashes already learned, refreshed in the background, and never blocks a transfer when the network is unavailable.
- **Encrypt Kalo-to-Kalo transfers (optional):** set a shared passphrase and enable encryption to wrap files in an authenticated container that only another Kalo with the same passphrase can open. Filenames and sizes are encrypted too, and standard OPP receivers keep working while encryption is off.
- **Approve incoming senders:** allow a file once, remember the sender, decline, or block. Choose **Trusted only** to reject unknown senders without prompting.
- **See transfer progress:** follow outgoing batches and incoming files in the desktop UI.
- **Cancel a batch:** interrupt an outgoing transfer, including during connection setup. The remaining files in the batch stop as well.
- **Choose where files go:** received files are written to a private staging area, scanned, and only then moved to your save folder, which defaults to the platform Downloads folder.
- **Keep received content inert:** Kalo never auto-opens or executes a received file. On Unix, files are saved with owner-only permissions; on Windows, Kalo writes Mark-of-the-Web so the shell treats them like downloads.
- **Switch themes:** use the dark **Kalo Midnight** or light **Kalo Daylight** appearance; the preference is remembered.
- **Keep Kalo in the panel:** on Linux, closing the window hides it to the status area when a StatusNotifierItem host is available.
- **Track activity:** view transfer results, errors, and receiver status in the app.
- **Use the CLI:** inspect adapters and devices, discover and pair, check receiver availability, and send files or folders from a terminal.

Kalo does not use a hosted service for file transfer and does not require sign-in.

## Platform support

| Platform | Current status | Packaging |
| --- | --- | --- |
| Ubuntu | Supported Linux target | Download the latest `.deb` or build it locally |
| Arch Linux / Omarchy | Supported Linux target | Download the latest `kalo-git` package or build it from the included `PKGBUILD`; not yet published to the AUR |
| macOS 11+ | **Send, device list, pairing and CLI supported. Receive uses macOS Bluetooth Sharing.** | Download the universal, ad-hoc signed `Kalo.app` ZIP or build it locally |
| Windows 10/11 | **Experimental; not yet tested on physical Windows hardware** | Download the latest portable ZIP or `.exe`; no installer |

## Requirements and compatibility

- A working Bluetooth adapter on the computer.
- A recipient that supports **Bluetooth OPP (Object Push Profile)** to receive files. Bluetooth support alone does not guarantee file-transfer compatibility.
- Pair the devices through your operating system's Bluetooth settings before sending, or use `kalo pair <MAC>` where supported. The desktop UI lists devices already **known to the operating system**; its **Refresh list** button reloads that list rather than initiating a new discovery scan.

**Ubuntu runtime dependencies:**

```sh
sudo apt install bluez bluez-obexd
```

**Arch Linux runtime dependencies:**

```sh
sudo pacman -S bluez bluez-obex
```

On Linux, Kalo uses BlueZ and `obexd`, plus an XDG desktop portal for the file picker. Ubuntu Desktop typically provides a portal; on Arch, install `xdg-desktop-portal-gtk`, or `xdg-desktop-portal-hyprland` on Hyprland/Omarchy, or another compatible portal backend if needed. No **separate Kalo daemon** needs to be enabled.

The Linux status-area icon uses StatusNotifierItem. KDE Plasma, Cinnamon, XFCE and Omarchy's Waybar (with its `tray` module) provide a host out of the box; GNOME needs an extension such as **AppIndicator and KStatusNotifierItem Support**. Without a compatible host, Kalo closes normally instead of hiding to the tray.

On macOS, Kalo uses Apple's IOBluetooth framework. Grant Bluetooth permission when macOS asks. Sending requires macOS 11 or newer and a paired destination. Receiving is not implemented in Kalo: enable **System Settings → General → Sharing → Bluetooth Sharing** and choose its destination folder. The macOS receiver runs outside Kalo, so Kalo's sender approval and malware scan do not apply to files received that way.

On Windows, Kalo uses WinRT Bluetooth APIs and its own RFCOMM/OBEX implementation; BlueZ, `obexd`, and D-Bus are not required. This path is still experimental, and there is no notification-area icon on Windows yet.

To compile from source, use a recent Rust toolchain (edition 2024; Rust 1.98 or newer is documented as working). Windows builds require the MSVC Rust toolchain, Visual Studio Build Tools, and the Windows SDK. macOS builds require Xcode Command Line Tools.

## Install and launch

### Download the latest build

GitHub Actions publishes stable asset names, so these links always resolve to the newest successful build:

- **Ubuntu `.deb`:** [kalo_amd64.deb](https://github.com/Ogalesha/Kalo/releases/latest/download/kalo_amd64.deb)
- **Arch Linux / Omarchy package:** [kalo-git-x86_64.pkg.tar.zst](https://github.com/Ogalesha/Kalo/releases/latest/download/kalo-git-x86_64.pkg.tar.zst)
- **macOS universal app:** [kalo-macos-universal.zip](https://github.com/Ogalesha/Kalo/releases/latest/download/kalo-macos-universal.zip)
- **Windows portable ZIP (experimental):** [kalo-windows-x64.zip](https://github.com/Ogalesha/Kalo/releases/latest/download/kalo-windows-x64.zip)
- **Windows standalone executable (experimental):** [kalo-windows-x64.exe](https://github.com/Ogalesha/Kalo/releases/latest/download/kalo-windows-x64.exe)
- **Checksums:** [SHA256SUMS.txt](https://github.com/Ogalesha/Kalo/releases/latest/download/SHA256SUMS.txt)

All published builds are listed on the [releases page](https://github.com/Ogalesha/Kalo/releases). The Arch, macOS, and Windows builds are not signed with a distribution certificate; verify downloaded files against the checksums.

### Ubuntu

Install the downloaded package:

```sh
sudo apt install ./kalo_amd64.deb
kalo
```

Or build from the root of a local checkout:

```sh
./packaging/ubuntu/build-deb.sh
sudo apt install ./dist/kalo_0.1.0-1_amd64.deb
kalo
```

The locally built `.deb` targets the architecture and glibc version of the build machine; it may not work on older Ubuntu releases. See [Ubuntu packaging notes](packaging/ubuntu/README.md).

Remove it with `sudo apt remove kalo`.

### Arch Linux / Omarchy

Install the downloaded package (the file is named `kalo-git-x86_64.pkg.tar.zst` and installs the `kalo-git` package):

```sh
sudo pacman -U kalo-git-x86_64.pkg.tar.zst
kalo
```

Or build the package from the root of a local checkout:

```sh
sudo pacman -S --needed base-devel git rust cargo
cd packaging/arch
makepkg -si
kalo
```

Both paths install the same `PKGBUILD` metadata, desktop entry, icon and manual page. The package uses the current `main` branch. It is **not yet published to the AUR**. See [Arch packaging notes](packaging/arch/README.md).

### macOS

Unzip `kalo-macos-universal.zip` and move `Kalo.app` to **Applications**. The build is ad-hoc signed but not notarized, so the first launch needs **Control-click → Open**, or **System Settings → Privacy & Security → Open Anyway**. Grant Bluetooth access when prompted.

Or build from the root of a local macOS checkout:

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
./packaging/macos/build-app.sh
open dist/Kalo.app
```

The script creates a universal `dist/Kalo.app` and `dist/kalo-macos-universal.zip`. Set `KALO_MACOS_UNIVERSAL=0` to build only the host architecture. See [macOS packaging notes](packaging/macos/README.md).

To receive files on macOS, enable **Bluetooth Sharing** in System Settings and use the folder it offers. Kalo's own receiver reports that it is unavailable on macOS; `kalo receive` explains the same limitation.

### Windows (experimental)

Download `kalo-windows-x64.zip`, unpack it, and run `kalo.exe`. You can also download the standalone `kalo-windows-x64.exe`. These builds are unsigned, so Windows SmartScreen may show a warning.

To build from the root of a Windows checkout with the MSVC toolchain installed:

```powershell
powershell -ExecutionPolicy Bypass -File packaging\windows\build-zip.ps1
```

Unpack the generated `dist\kalo-<version>-<arch>.zip` and run `kalo.exe`. There is no Windows installer, notification-area icon, or background receiver service yet. See [Windows packaging notes](packaging/windows/README.md).

### Run directly from source

```sh
cargo build --release
./target/release/kalo
```

On Windows, run `.\target\release\kalo.exe` instead. `kalo ui` explicitly opens the graphical interface on every supported build target.

## How to use Kalo

### Send files or a folder

1. Turn on Bluetooth and pair the destination device using your system settings.
2. Make sure the destination can receive Bluetooth OPP file transfers.
3. Open Kalo. Under **Choose a device**, select the destination; use **Refresh list** if you have just paired it.
4. Under **Choose files**, select one or more files, or use **Choose folder** to send a folder tree (hidden entries and symbolic links are skipped). Kalo shows the number of files and the total size before sending.
5. Select **Send to [device]**. Kalo checks every file against the malware blocklist, then sends the batch sequentially and lets you cancel it.

The recipient may need to accept each transfer, depending on its own Bluetooth software. OPP has no folder concept, so Kalo flattens folder contents and sends the files themselves.

### Encrypt files between Kalo devices (optional)

Kalo can protect file contents from a passive Bluetooth capture even when the Bluetooth link itself is not encrypted. This works only when **both devices run Kalo and share the same passphrase**. Encryption is off by default.

1. On both devices, open Kalo and find **File encryption** under the receiver settings.
2. Type the same passphrase (at least 12 characters) on each device and choose **Save**. The passphrase is stored in Kalo's private settings file.
3. On the sending device, switch **Outgoing encryption** to **On**.
4. Send as usual. The receiver decrypts the file automatically when its passphrase matches, scans the decrypted content against the malware blocklist, and saves it under the original name.

Kalo derives a key with Argon2id (64 MiB, 3 passes), encrypts the original filename and size, and authenticates every 1 MiB chunk plus a final record with XChaCha20-Poly1305. A wrong passphrase, tampering, truncation, or trailing data is rejected, and the container is deleted instead of saved. The Bluetooth peer can still see a random `.kalo` container name and its ciphertext size, but not the original filename, size, or contents.

**Compatibility:** a stock OPP receiver, or a Mac using Apple's Bluetooth Sharing, cannot open an encrypted container and will save it as an opaque `.kalo` file. Turn encryption off when sending to a device that does not run Kalo with the same passphrase. The CLI reads the same saved settings, so configure the passphrase in the app before using `kalo send` with encryption enabled.

### Receive a file

1. Open Kalo and check the receiver status at the top of the window. When it says **Ready to receive**, another compatible device can send a file to this computer.
2. The first time a sender is seen, an approval card shows the sender, Bluetooth address, file name and size. Choose **Allow once**, **Always allow**, **Decline** or **Block**. If the address is unknown, only the one-time choices are offered.
3. Watch progress under **Incoming files**. The staged file is scanned against the malware blocklist, then saved to the folder shown under **Save to**; use **Open folder** to reveal the result.

An incoming Kalo container is decrypted first when a passphrase is configured, and the decrypted content is scanned before saving. If the passphrase is missing or wrong, or the container is corrupted, the container is deleted and nothing is saved.

Use **Senders** to review remembered devices, remove a decision, or switch between **Ask** and **Trusted only**. **Trusted only** rejects unknown senders without showing a prompt. The CLI receiver has no prompt and rejects unknown senders; run the desktop app to approve new devices.

**Important:** acceptance also depends on the operating system's Bluetooth stack. On Linux, a different program (such as Blueman's transfer service) may already own the OBEX agent registration. Close or disable the conflicting receiver; Kalo retries automatically. On Windows, Kalo must stay open to receive files. On macOS, Kalo cannot host the receiver at all; use Bluetooth Sharing.

## Command-line interface

```text
kalo                         Open the desktop UI
kalo ui                      Open the desktop UI
kalo adapters                List Bluetooth adapters and their state
kalo connectable [on|off]    Show or set adapter connectability (show-only on Windows and macOS)
kalo devices [--discovery N] List known devices; optionally discover for N seconds
kalo pair <MAC>              Pair with a device
kalo agent-check             Check whether the receiver can start
kalo send <MAC> <FILES>...   Send files or folders via Bluetooth OPP
kalo receive                 Run the receiver in the foreground
```

For example:

```sh
kalo devices --discovery 15
kalo pair AA:BB:CC:DD:EE:FF
kalo send AA:BB:CC:DD:EE:FF path/to/file.pdf
kalo send AA:BB:CC:DD:EE:FF path/to/folder path/to/another-file.zip
```

The CLI uses the same settings as the desktop app. Configure the encryption passphrase in the app first; there is no passphrase command-line flag, so the secret does not end up in shell history or process arguments.

## Security

Kalo's goal is to be useful for file transfer without becoming a remote-access tool or a malware relay.

- **Files only, in both directions.** Kalo implements Object Push, not dial-up networking, serial-port, HID, or remote-control profiles. It never executes or opens transferred content, and it exposes no command channel to a peer. The macOS receiver is Apple's Bluetooth Sharing, not a Kalo control service.
- **Malware hash blocklist.** Outgoing files are hashed and refused if their SHA-256 digest is on the list. Incoming files are written to a private staging area, hashed, and deleted instead of saved when blocked. The list combines a bundled baseline with the MIT-licensed [romainmarcoux/malicious-hash](https://github.com/romainmarcoux/malicious-hash) feeds, fetched from raw GitHub and jsDelivr, cached under Kalo's config directory, refreshed at most daily in the background, and stored as sorted binary hashes for low memory use. Refreshes merge hashes already cached, so a compromised endpoint cannot silently remove a known detection.
- **Optional app-layer encryption.** With a shared passphrase, Kalo wraps outgoing files in an authenticated `KALOENC1` container using Argon2id and XChaCha20-Poly1305. The original filename and size are encrypted; each 1 MiB chunk and a final record are authenticated, so tampering, truncation, reordering, and trailing data are rejected. Only Kalo with the same passphrase can decrypt the result; stock OPP receivers see an opaque container. Encryption is off by default and never replaces the malware scan: the receiver decrypts into private staging and scans the plaintext before saving.
- **Sender approval.** Incoming pushes from unknown Bluetooth addresses wait for an explicit decision or are rejected. Decisions are keyed by normalized Bluetooth address; Windows identities that only have a name are never remembered.
- **Hardened file handling.** Remote filenames are stripped of path separators, control characters, Windows alternate-data-stream characters, trailing dots/spaces, and reserved device names. Symlinks and special files are not sent. Received files keep owner-only permissions on Unix and get Mark-of-the-Web on Windows. Announced and actual sizes are checked against the OPP 4 GB cap, free space is checked on both the save and staging filesystems, and oversized staged data is deleted instead of saved.
- **Bounded resource use.** Hashing streams with a 64 KiB buffer; incoming concurrency, file count, file size, feed size, and blocklist memory are capped. Unknown-size transfers keep checking free space while they grow, and Windows re-checks every 64 MiB. Refresh failures fall back to the last cached list and never block a transfer.

The complete threat model, guarantees, and non-goals are in [SECURITY.md](SECURITY.md).

## How it works (technical overview)

**Outgoing transfers:** Kalo selects a device and sends files using Bluetooth OPP/OBEX. On Linux, it delegates the OBEX transfer to `obexd` through D-Bus; on Windows, its experimental backend connects to the remote OPP service using WinRT RFCOMM and a built-in OBEX engine; on macOS, it uses `IOBluetoothOBEXSession` and `OBEXFileTransferServices` on a worker that pumps its own run loop. A batch shares one cancellation token and sends files sequentially. When encryption is on, Kalo checks that every encrypted container will still fit the OPP limit, derives one Argon2id key for the batch, writes each container to a private temporary directory, and sends its random name; each container is removed when its send completes, is canceled, or fails. Progress, cancellation, and stall handling are reported to the UI or CLI.

**Incoming transfers:** Kalo starts a receiver when the UI runs (or when `kalo receive` is invoked) on Linux and Windows. Before a transfer is accepted, the shared authorizer checks the persisted trust store. Unknown senders are announced to the UI and wait for a decision or a timeout; the CLI rejects them. Accepted transfers first go into a private staging directory, where filenames are sanitized, size and free space are checked, and transfer results are verified. An encrypted container is decrypted into a private temporary file, checked against its authenticated plaintext size and available space, hashed against the blocklist, and only then moved into the configured save folder under its original name. When possible, partial files are recovered rather than silently discarded. macOS has no public OPP receiver API, so the macOS backend reports that clearly and points at Bluetooth Sharing.

**Trust storage:** decisions are keyed by normalized Bluetooth address and stored in Kalo's configuration directory (`$XDG_CONFIG_HOME/kalo/trust.json` on Linux, `~/Library/Application Support/Kalo/trust.json` on macOS, and the roaming application data folder on Windows). Theme, save-folder, outgoing-encryption, and passphrase preferences live in `settings.json` next to it; the settings file is owner-only on Unix. Name-only identities are never persisted.

**Receiver reliability:** Linux uses an OBEX agent registered with `obexd`, with retries after service or session-bus interruptions. On Windows, Kalo advertises its own OPP service while the app is running. A shared event system keeps transfer and receiver status consistent between the UI and CLI.

**Desktop integration:** the Linux status-area icon uses StatusNotifierItem and offers **Open Kalo** and **Quit Kalo**. Closing the window hides it when the tray is available, so the receiver keeps running in the background.

## Known limitations

- **There is no reciprocal trusted-PC handshake yet.** Remembering a sender on one computer does not automatically trust the other computer in return. Each side currently approves the other separately.
- **macOS cannot receive through Kalo.** Apple exposes no public OPP receiver API, so Kalo uses the system Bluetooth Sharing service for incoming files. That service is outside Kalo's approval prompt and malware scan.
- **macOS has not been validated on Apple hardware by this project.** The backend is type-checked and CI builds and smoke-tests the app bundle, but pairing, sending, and permission prompts still need real-device testing.
- **Windows is experimental.** Sending, receiving, pairing, trust persistence and Bluetooth radio edge cases need tests on physical Windows 10/11 machines. Windows builds are unsigned and there is no notification-area icon yet.
- **The GUI does not perform active discovery.** It refreshes the operating system's known-device list; the CLI supports timed discovery.
- **On Linux, only one OBEX agent can occupy the registration slot at a time.** Other Bluetooth transfer tools can conflict with Kalo's receiver.
- **The Linux tray depends on the desktop.** GNOME requires an AppIndicator extension; without a StatusNotifierItem host, Kalo cannot hide to the panel.
- **Linux packages built locally are tied to the build machine.** Binary compatibility across different distributions, architectures, or older glibc versions is not guaranteed.
- **Encryption is optional, Kalo-only, and off by default.** Without it, confidentiality depends on the Bluetooth link encryption provided by pairing and the operating system. A stock OPP receiver or Apple's Bluetooth Sharing cannot open a Kalo container and saves it as an opaque file.
- **Encryption has no forward secrecy or sender identity.** One shared passphrase protects every container; anyone who learns it can decrypt captured containers later and can also create containers the receiver will accept. There is no per-transfer key exchange, rotation, revocation, or proof of which device sent a file.
- **The passphrase is stored in plaintext in Kalo's settings file.** The file is owner-only on Unix (`0600`) and lives in the private app-data directory on Windows, but any process or user that can read it can recover the passphrase. OS keyring storage is future work.
- **Encrypted outer metadata remains visible.** The Bluetooth peer sees a random `.kalo` container name and the ciphertext size; the original filename and plaintext size are encrypted. A saved decrypted file is ordinary plaintext at rest.
- **Hash checks are a blocklist, not a guarantee.** A malicious file with an unknown hash is not detected. Keep the app updated and treat unexpected files with care.
- **File transfer requires OPP support on the peer.** Not all Bluetooth devices implement it.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

To type-check the Windows target from Linux, with the target and its prerequisites installed:

```sh
cargo clippy --target x86_64-pc-windows-msvc --all-targets -- -D warnings
```

The untrusted-input parsers have libFuzzer targets under `fuzz/`. They need a nightly toolchain and `cargo-fuzz`:

```sh
cargo +nightly install cargo-fuzz --locked
cargo +nightly fuzz run obex_parser -- -max_total_time=60
cargo +nightly fuzz run filename -- -max_total_time=60
```

Shared modules cover the `iced` UI, platform interface, receiver status, event handling, settings, trust decisions, selection handling, cancellation, security policy, encryption containers, and download paths. Receiver filename sanitization is compiled on Linux and Windows, where Kalo hosts the incoming transfer. Linux-specific modules integrate with BlueZ and `obexd`; Windows-specific modules implement WinRT RFCOMM/OBEX operations; macOS-specific modules use IOBluetooth.

The [GitHub Actions workflow](.github/workflows/ci.yml) runs formatting, Clippy and tests on Linux, macOS and Windows, builds and smoke-tests the Ubuntu `.deb`, the Arch Linux `kalo-git` package, the universal macOS app and the experimental Windows ZIP/EXE, and publishes them to the rolling latest release only after all builds succeed. The UI includes a debug-only demo mode (`KALO_DEMO=1`, with `KALO_DEMO_THEME=light` for the light appearance) used to capture the screenshots without exposing real devices.

## License

Released under the [MIT License](LICENSE).
