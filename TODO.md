# Kalo — TODO

## Product and UI

- [ ] **Modernize the UI further.** The current Operate surface is clear and
      polished, but the next visual pass should push the product identity:
      a more contemporary layout, stronger typography, richer empty and
      progress states, and a deliberate light/dark theme system.
- [ ] Add screenshots and a short demo to the README.
- [ ] Per-device trust and authorization for incoming files (replace accept-all).
- [ ] Save-location preference and an "Open folder" action after a transfer.

## Platform support

- [x] **Ubuntu** — Rust/iced app, BlueZ + obexd backend, `.deb` packaging in
      `packaging/ubuntu/`, build script and desktop assets.
- [ ] **Arch Linux** — reuse the Linux backend; add a `PKGBUILD`, `.SRCINFO`,
      correct BlueZ/obexd dependencies, test on a clean Arch install, and
      publish to the AUR.
- [ ] **Windows** — the current architecture depends on BlueZ, obexd and D-Bus,
      so Windows needs a separate Bluetooth/OBEX backend and packaging
      (MSI or portable ZIP). Keep the UI and event contract shared.

## Engineering

- [ ] Run the requested implicit state-machine audit, review the prioritized
      findings, and apply only approved minimal fixes with regression tests.
- [ ] Add CI for `fmt`, `clippy`, tests and package builds.
- [ ] Add an end-to-end transfer test harness with two virtual Bluetooth
      adapters where the environment allows it.
