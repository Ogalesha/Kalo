# Kalo — TODO

## Product and UI

- [x] **Modernize the UI.** Midnight visual system, branded hero, card-based
      layout, step-based send flow, richer empty/progress states and a custom
      iced theme.
- [ ] Add a light/dark theme switch and persist the preference.
- [ ] Add screenshots and a short demo to the README.
- [ ] Per-device trust and authorization for incoming files (replace accept-all).
- [ ] Save-location preference and an "Open folder" action after a transfer.

## Platform support

- [x] **Ubuntu** — Rust/iced app, BlueZ + obexd backend, `.deb` packaging in
      `packaging/ubuntu/`, build script and desktop assets.
- [x] **Arch Linux packaging** — `kalo-git` PKGBUILD and `.SRCINFO` in
      `packaging/arch/`, shared desktop assets and correct BlueZ/obexd/portal
      dependencies.
- [ ] Test `kalo-git` on a clean Arch install and publish it to the AUR.
- [ ] **Windows** — the current architecture depends on BlueZ, obexd and D-Bus,
      so Windows needs a separate Bluetooth/OBEX backend and packaging
      (MSI or portable ZIP). Keep the UI and event contract shared.

## Engineering

- [x] Run the implicit state-machine audit and apply the approved fixes with
      regression tests: partial-file preservation, cancel-aware send preflight,
      a single receiver status source, stale `Release` isolation, shared
      receiver supervision, discovery cleanup, per-status stall policies,
      interval-based watchdogs, pairing timeouts and periodic staging recovery.
- [ ] Add CI for `fmt`, `clippy`, tests and package builds.
- [ ] Add an end-to-end transfer test harness with two virtual Bluetooth
      adapters where the environment allows it.
