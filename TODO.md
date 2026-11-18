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
- [ ] Add an end-to-end transfer test harness with two virtual Bluetooth
      adapters where the environment allows it.
