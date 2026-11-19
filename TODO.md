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
- [x] **Two-way trusted peers.** SPAKE2 pairing over OPP pins an Ed25519
      identity on both devices, derives independent directional ratchets, and
      writes reciprocal trust so neither side prompts again. Pairing is
      available on Linux and Windows; macOS can initiate but has no receiver
      to answer.
- [x] **Downloads/Kalo folder.** Incoming files save to
      `Downloads/Kalo/<sender>/`, with `Recovered` for files recovered
      without a known sender. The sender label uses the Linux BlueZ alias or
      the Windows remote name, falling back to the normalized address.
- [x] **`_n` collision suffix.** Repeated names use `name_1.ext`,
      `name_2.ext`, … and never overwrite an existing file.

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
- [x] **Application-layer encryption for sent files.** Optional Kalo-to-Kalo
      containers with a shared passphrase: Argon2id (64 MiB, 3 passes) plus
      XChaCha20-Poly1305, encrypted filename and size metadata, authenticated
      1 MiB chunks and a final record, fresh nonces, private temporary
      containers, decrypt-scan-move on receive, and documented limits in
      README and SECURITY. Off by default because stock OPP receivers cannot
      open a container; the outer random name and ciphertext size remain
      visible to the Bluetooth peer.
- [x] **Keyring-backed passphrase storage.** The shared passphrase lives in
      the OS keyring (`Kalo` / `encryption-passphrase`). Plaintext values are
      migrated on load; if no keyring is available Kalo warns and falls back
      to the owner-only settings file so the receiver still works.
- [x] **Authenticated per-device key exchange.** Pairing uses SPAKE2 over the
      shared passphrase and pins an Ed25519 identity. Paired transfers use
      `KALOENC2` with signed, directional HMAC-SHA256 hash ratchets, bounded
      forward skipping, replay rejection, and automatic encryption. The
      shared-passphrase `KALOENC1` mode remains for unpaired compatibility.
- [ ] **Pairing fingerprint verification.** Add an out-of-band fingerprint
      comparison or QR/display code so users can verify the pinned identity
      instead of trusting the first SPAKE2 exchange.

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

## Full security audit and automatic remediation (planned)

Execute this as one dedicated pass over the whole repository. It is an
implementation task, not a report-only review: fix every confirmed
vulnerability that can be safely fixed, add regression tests, and document
what remains. Do not commit, push, publish, or modify remotes unless the
user explicitly authorizes it.

Rules: inspect the real code before concluding; never invent findings,
builds, or guarantees; separate confirmed vulnerabilities from plausible
risks and false positives; prefer root-cause fixes; fail closed; never
weaken crypto, validation, authorization, or permissions to get a green
build; never expose secrets in reports or logs; use isolated or mocked
environments for destructive tests; do not probe unrelated devices.

- [ ] **Phase 1 — Reconnaissance and threat model.** Map every module under
      `src/`, the BlueZ/obexd and WinRT/RFCOMM/OBEX stacks, send/receive and
      staging pipelines, filename handling, trust/authorization, crypto and
      secret storage, async tasks, GUI/CLI lifecycle, packaging (Ubuntu,
      Arch, Windows), CI, and diagnostics. Enumerate entry points, trust
      boundaries, external inputs, privileged operations, and
      security-sensitive state transitions. Model assets, attacker
      capabilities (especially a nearby Bluetooth device), local and remote
      surfaces, abuse scenarios, existing controls, and gaps.
- [ ] **Phase 2 — Deep audit.** Review Bluetooth/OBEX/RFCOMM authorization,
      packet parsing, lengths/overflow, state transitions, replays,
      disconnects, resource exhaustion, cancellation, receiver restarts and
      registration conflicts. Review filesystem handling for traversal,
      symlink/hardlink and TOCTOU attacks, staging names, collisions,
      overwrites, recovery, Unicode/normalization, Windows ADS/reserved
      names, permissions, disk exhaustion, and atomicity. Review Rust memory
      and runtime safety, `unsafe`/FFI, panics on untrusted input,
      allocations, cancellation safety, zeroization, and error handling.
      Review concurrency, deadlocks, double completion/cancellation, stale
      events, orphaned tasks, watchdogs, timeouts, and recovery. Audit direct
      and transitive dependencies with `cargo audit`, `cargo deny`, Clippy,
      Semgrep or equivalents, secret scanning, and fuzzing where useful; fix
      compatible vulnerable dependencies without unrelated churn. Review
      crypto use, randomness, KDF parameters, nonces, AEAD, key lifecycle,
      permissions, and accidental disclosure. Review GUI/CLI parity, argument
      validation, subprocess safety, log injection, path exposure, and
      security indicators. Audit packaging permissions, scripts, download
      integrity, artifact contamination, privilege requirements, and release
      provenance.
- [ ] **Phase 2 special — incoming authorization.** Verify whether
      accept-all incoming authorization still exists. If it does, implement
      explicit consent and/or trusted devices, default-deny unsolicited
      transfers, do not silently trust every paired device, keep CLI and GUI
      consistent, enforce equivalent Linux/Windows decisions where feasible,
      and prevent bypass across receiver restarts or races. Handle an
      unavailable UI safely. Add negative tests proving unauthorized
      transfers are rejected.
- [ ] **Phase 3 — Automatic remediation.** For each finding: root cause,
      exploitability/impact, justified severity (Critical/High/Medium/Low/
      Informational), affected files/functions, smallest robust fix,
      implementation, focused regression test, checks, patch inspection, and
      documentation updates. Prioritize Critical and High, then Medium and
      Low. Report limitations precisely instead of claiming a fix that was
      not validated.
- [ ] **Phase 4 — Adversarial tests.** Add deterministic tests for malicious
      filenames, traversal, Unicode/path edges, symlink and collision races,
      corrupt/truncated OBEX frames, inconsistent lengths, oversized inputs,
      unauthorized transfers, interrupted connections, repeated
      cancellation, concurrent transfers, receiver restarts, disconnects,
      disk-full/permission failures, recovery failures, watchdog boundaries,
      and resource exhaustion. Use property-based testing and fuzzing where
      meaningful; keep protocol-level mocks and isolated adapters. Separate
      simulated coverage from hardware validation.
- [ ] **Phase 5 — Validation.** Run `cargo fmt --all -- --check`,
      `cargo clippy --all-targets -- -D warnings`, `cargo test --all-targets`,
      `cargo build --release`, and `cargo audit`. Add target-specific checks;
      validate Linux and Windows separately; cross-compile when hardware is
      unavailable without claiming physical-device testing. Record every
      failure and distinguish defects from missing tooling.
- [ ] **Phase 6 — Second independent audit.** Re-review the modified code
      for incomplete fixes, new authorization bypasses, races, regressions,
      functionality loss, cross-platform divergence, unhandled failures,
      permissive fallbacks, new vulnerable dependencies, and configuration
      changes. Remediate and retest until no additional actionable issue is
      found or a clear blocker is documented. Never claim zero
      vulnerabilities.
- [ ] **Phase 7 — Permanent hardening.** Add practical CI security checks,
      dependency advisory scanning, formatting/lint gates, security
      regression tests, cross-platform build checks, safe dependency update
      workflow, fuzz targets for parsers, maintain `SECURITY.md`, and
      document trust boundaries, authorization behavior, and residual
      limitations without excessive CI cost or unmaintainable complexity.
- [ ] **Deliverables.** Implement the actual code changes; create
      `SECURITY_AUDIT.md` (scope, threat model, methodology/tools, findings
      and evidence, severity rationale, affected files, exploitability,
      remediation, tests, verification, residual risks, platform limits);
      create `REMEDIATION_SUMMARY.md` (confirmed/fixed/unresolved findings,
      dependency updates, modified files, new controls/tests, commands and
      results, environment limits, next steps); end with the required
      "SECURITY AUDIT RESULTS" assessment and the five most important
      findings, exact changes, executed tools, unresolved issues, and
      remaining manual validation. Every number must map to a documented
      finding or executed check.
