# Kalo — TODO

## Product and UI

- [x] **Modernize the UI.** Midnight visual system, branded hero, card-based
      layout, step-based send flow, richer empty/progress states and custom
      iced themes.
- [x] Add a light/dark theme switch and persist the preference.
- [x] Add screenshots and a short demo to the README.
- [x] Per-device trust and authorization for incoming files. New senders are
      approved in the window; decisions are remembered by Bluetooth address.
- [x] Save-location preference and an "Open folder" action after a transfer.
- [x] Brand icon and Linux status-area icon, working in horizontal and vertical
      panels through StatusNotifierItem.
- [x] **Single file, multiple files and folder sending.** The window can pick
      either files or a folder tree; folders are flattened, hidden entries and
      symlinks are skipped, the selection is capped and sorted, and the batch
      shares progress and cancellation.
- [ ] **Two-way trusted peers.** Once two computers trust each other, transfers
      should need no approval in either direction. Today each receiver can
      remember a sender, but there is no reciprocal trust handshake yet.
- [ ] **Downloads/Kalo folder.** Save incoming files in a `Kalo` folder inside
      the platform Downloads folder by default, instead of directly in
      Downloads.
- [ ] **`_n` collision suffix.** When a received file has the same name as an
      existing file, use `name_1.ext`, `name_2.ext`, … instead of the current
      `name (1).ext` form.

## Platform support

- [x] **Ubuntu** — Rust/iced app, BlueZ + obexd backend, `.deb` packaging in
      `packaging/ubuntu/`, build script and desktop assets.
- [x] **Arch Linux packaging** — `kalo-git` PKGBUILD and `.SRCINFO` in
      `packaging/arch/`, shared desktop assets and correct BlueZ/obexd/portal
      and X11/Wayland dependencies. Built and installed in a clean Arch Linux
      container, checked with `namcap`, and the GUI started under Xvfb and a
      headless Wayland compositor; CI builds and publishes the package as
      `kalo-git-x86_64.pkg.tar.zst`.
- [ ] Validate `kalo-git` on a real Omarchy/Hyprland desktop (tray host and
      portal file picker) and publish it to the AUR.
- [x] **Windows backend (experimental)** — native WinRT RFCOMM transport, OPP
      sender with progress/cancel/watchdog, incoming OPP service advertisement
      and streaming receiver, device listing/discovery/pairing, and the shared
      `platform` facade, event contract and UI.
- [ ] Validate the Windows backend on real Windows 10/11 hardware: send,
      receive, pairing prompts, radio off/on, service conflicts and path
      handling. Remove the experimental label only after that.
- [x] **Windows portable ZIP** — `packaging/windows/build-zip.ps1` builds
      `dist\kalo-<version>-<arch>.zip` with the executable, icon, README and
      license.
- [ ] Add an MSI/WiX installer, Start-menu entry and code signing for Windows.
- [ ] Add a Windows notification-area icon equivalent to the Linux tray.
- [x] **macOS sender and device backend** — IOBluetooth OPP sender with
      progress, cancellation and stall handling; paired/recent device listing;
      optional inquiry; pairing; adapter state; CLI support.
- [x] **macOS app bundle** — `packaging/macos/build-app.sh` builds a universal
      `Kalo.app` with the Bluetooth usage description, generated `.icns` and
      ad-hoc signature, and CI uploads `kalo-macos-universal.zip`.
- [ ] Validate the macOS backend on Apple hardware: Bluetooth permission
      prompt, pairing, send to a phone/PC, radio off/on, and codesigning.
- [ ] **macOS receiver.** Apple exposes no public OPP server API. Continue
      pointing users to Bluetooth Sharing unless a supported API appears.

## Security

- [x] **Malware hash blocklist.** Bundle a baseline, merge the MIT-licensed
      `romainmarcoux/malicious-hash` SHA-256 feeds, cache under the private
      config directory, refresh daily in the background, and scan on both send
      and receive.
- [x] **Sender authorization.** Ask by default, remember allow/block decisions
      by Bluetooth address, provide a Trusted-only policy, and reject unknown
      senders in the CLI.
- [x] **Filename sanitization.** Remove path separators and control
      characters; neutralize Windows alternate-data-stream characters, trailing
      dots/spaces and reserved device names.
- [x] **Receive hardening.** Private staging, announced and actual size caps,
      free-space checks on both the save and staging filesystems, periodic
      re-checks while unknown-size transfers grow (every 64 MiB on Windows),
      deletion of oversized staged data before it reaches the save folder,
      bounded concurrency, Windows incremental hashing, scan-before-save,
      deletion of blocked files, owner-only permissions on Unix, and
      Mark-of-the-Web on Windows.
- [x] **No remote control and no automatic opening.** OPP only; no execution,
      preview, shell, or remote-control profile; received content stays inert.
- [x] **Two blocklist endpoints and an append-only cache.** Each feed file
      is fetched from raw GitHub and jsDelivr, refreshed results merge the
      hashes already cached (up to 500,000), a truncated refresh is rejected,
      and parsing/downloads are bounded. A compromised endpoint can add false
      positives but cannot silently remove a known hash. Signed manifests
      remain an optional future strengthening.
- [x] **Fuzz the Windows OBEX parser and filename sanitizer.** `fuzz/` contains
      libFuzzer targets for `obex_protocol::transport::PacketStream` and
      `sanitize::filename`; CI runs both for 60 seconds and uploads artifacts
      on failure. Fuzzing already caught and fixed a truncation path that could
      leave a trailing space after the 200-byte cap.
- [ ] **Application-layer encryption for sent files.** Encrypt file contents so
      a passive Bluetooth capture cannot read them even when the link itself is
      not encrypted. This is possible only between two Kalo peers, which must
      share a key or run an authenticated key exchange; stock OPP receivers
      cannot decrypt a custom container. Filename and size would still be
      visible to the network. Pairing already enables Bluetooth link
      encryption, but it is not an app-layer guarantee.

## Engineering

- [x] Run the implicit state-machine audit and apply the approved fixes with
      regression tests: partial-file preservation, cancel-aware send preflight,
      a single receiver status source, stale `Release` isolation, shared
      receiver supervision, discovery cleanup, per-status stall policies,
      interval-based watchdogs, pairing timeouts and periodic staging recovery.
- [x] Add CI for `fmt`, `clippy`, tests, Linux package builds, a Windows
      `clippy`/test job and rolling GitHub downloads for the latest successful
      `.deb`, Arch `kalo-git` package, Windows ZIP and Windows `.exe`. The
      Windows executable is smoke-tested with `--version` and `--help`, and the
      Arch package is installed and smoke-tested in an Arch container.
- [x] Add a macOS CI job that runs Clippy and tests, builds the universal app
      bundle, smoke-tests it, and publishes `kalo-macos-universal.zip` with
      checksums.
- [ ] Add an end-to-end transfer test harness with two virtual Bluetooth
      adapters where the environment allows it.
