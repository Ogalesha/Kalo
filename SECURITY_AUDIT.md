# Kalo security audit

Date: 2026-11-21/22
Baseline: `86082ae` (`Add per-sender folders, keyring storage, and authenticated pairing`)
Status: findings and fixes are in the working tree; nothing in this audit was
committed or pushed.

This document records a full audit of the repository, the fixes applied, the
tests that exercise them, and what remains. It is not a claim that Kalo has
zero vulnerabilities. The companion file `REMEDIATION_SUMMARY.md` lists the
changes, commands, and the required final assessment.

## 1. Scope

In scope:

- every module under `src/`, including the Linux/BlueZ/obexd receiver, the
  Windows WinRT/RFCOMM/OBEX receiver, the macOS sender, the shared OBEX
  parser, send/receive pipelines, staging and recovery, filename handling,
  trust and authorization, pairing, containers and key chains, settings and
  secret storage, GUI/CLI lifecycle, and async task handling;
- packaging under `packaging/ubuntu`, `packaging/arch`, `packaging/windows`,
  and `packaging/macos`;
- CI under `.github/workflows/`;
- direct and transitive dependencies recorded in `Cargo.lock`.

Out of scope: compromise of the host OS or Bluetooth firmware, physical
access, vulnerabilities in third-party advisory data, and exhaustive
protocol conformance testing against real phones. Local and remote denial of
service is in scope only up to the point where Kalo can bound its own
resource use.

## 2. Assets, trust boundaries, and adversaries

Assets: the user's files and their confidentiality/integrity, host integrity,
transfer metadata, the encryption passphrase, the Ed25519 device identity,
pinned peer identities and ratchet state, trust decisions, and receiver
availability.

Trust boundaries:

- Bluetooth peer -> OBEX parser -> staging;
- staging -> authorization -> decryption -> malware scan -> save folder;
- peer address/name -> trust store lookup;
- UI/CLI -> trust store, settings, and keyring;
- local config/cache files -> process;
- network feed -> malware blocklist;
- CI/release inputs -> published artifacts.

Adversaries considered: a nearby Bluetooth device (including one spoofing a
known address), a malicious filename or container, a malformed or truncated
OBEX stream, a compromised or unavailable malware-hash endpoint, an
unprivileged local user on a multi-user machine, and a local user who can
write to shared temporary directories. A local attacker who can already write
the user's private configuration directory is treated as host compromise.

## 3. Methodology and tools

- Manual threat enumeration and line-by-line review of every module and
  packaging script, plus review of the trust and pairing state machine.
- Targeted regression tests for each confirmed issue; property-style inputs
  for filenames and parsers.
- `rustfmt`, Clippy with `-D warnings`, the full test suite, release build,
  Windows GNU cross-target Clippy, `cargo-audit` 0.23.0, libFuzzer targets
  (`fuzz/obex_parser`, `fuzz/filename`), YAML validation of CI, and a
  repository secret scan.
- `cargo-deny` and Semgrep were not installed in this environment, so they
  were not run. This is a documented gap, not a claim that their checks are
  redundant.

No destructive tests were run, no real Bluetooth devices were probed, and no
network services outside the project's own feed endpoints and advisory
database were contacted.

## 4. Findings

Eighteen findings were confirmed and remediated in the working tree: 2 High,
7 Medium, 8 Low, and 1 Informational. `Fixed` means the code change and the
listed verification exist; it does not mean the class of bug is impossible.

| ID | Severity | Status | Finding |
| --- | --- | --- | --- |
| F-01 | High | Fixed | Paired Bluetooth address accepted plaintext and shared-passphrase containers |
| F-02 | High | Fixed | Trust-store persistence could write an older snapshot over newer state |
| F-03 | Medium | Fixed | Incoming ratchet rejected legitimate forward skips / could not resume after failed sends |
| F-04 | Medium | Fixed | Blocklist refresh could evict previously cached detections |
| F-05 | Medium | Fixed | Pairing pending state was unbounded and a duplicate request could replace an in-flight handshake |
| F-06 | Medium | Fixed | Pairing replies spawned unbounded background workers |
| F-07 | Medium | Fixed | Linux authorization waits were not counted against the incoming concurrency limit |
| F-08 | Medium | Fixed | Windows created a thread per connection before enforcing the connection limit |
| F-09 | Low | Fixed | Sender could downgrade when a pinned entry had no usable incoming chain |
| F-10 | Medium | Fixed | Windows kept identity/trust in roaming data and staging in the shared temp path |
| F-11 | Low | Fixed | Outgoing and pairing temporary files lived under a shared temp path |
| F-12 | Low | Fixed | Received files could briefly be group/world-readable during a move or copy |
| F-13 | Low | Fixed | Settings temp file used `File::create` and the process umask before chmod |
| F-14 | Low | Fixed | Bidi/zero-width format controls could spoof filenames and peer labels |
| F-15 | Low | Fixed | Windows peer names were not stripped of format/control characters |
| F-16 | Low | Fixed | Filename length cap could be exceeded after a reserved-name prefix (found by fuzzing) |
| F-17 | Low | Fixed | Off-by-one at the exact maximum ratchet skip made a valid container uncommittable |
| F-18 | Info | Fixed | CI actions were tag-pinned and dependencies were not audited |

### F-01 (High) Paired-address downgrade

Root cause: the receiver checked whether an address was fully paired only for
some paths. It had no check that a file arriving from an address with a
pinned peer identity was actually a `KALOENC2` container. A plaintext push or
a `KALOENC1` shared-passphrase container from that address was processed as
an ordinary incoming file.

Impact: a nearby impersonator, or an older/downgraded sender, could deliver
unauthenticated content under the identity of a paired device. The malware
scan still applied, and Kalo never executes files, but the pairing
authentication guarantee was bypassed.

Fix: `TrustStore::is_pinned` reports an allowed entry with a pinned key even
if a ratchet direction is missing. `src/agent.rs::finish_transfer` and
`src/win/receiver.rs::finish_transfer` delete plaintext and non-peer
containers from such an address before scanning or saving. `is_pinned`
rather than `is_paired` is used, so a partially damaged pairing entry still
fails closed.

Tests: `agent::tests::a_paired_sender_cannot_downgrade_to_plaintext`,
`agent::tests::a_paired_sender_cannot_downgrade_to_the_shared_passphrase`,
and `trust::tests::pinned_identity_is_visible_without_ratchet_chains`.
`SECURITY.md` and `README.md` document the behavior.

### F-02 (High) Trust-store persistence rollback

Root cause: `TrustStore::persist` cloned the state while holding the data
lock and then serialized the clone after releasing it. Two overlapping
writers could write out of order: the older snapshot could land last.

Impact: after a restart, a removed/blocked decision or a consumed ratchet
step could reappear. That is an authorization rollback and can reopen replay
of an old container. The race is narrow and requires overlapping writes, so
the finding is High rather than Critical.

Fix: `persist` holds the data lock through serialization and the atomic file
write (`src/trust.rs`). Readers still block briefly during the write, but no
stale snapshot can overwrite newer state.

Test: `trust::tests::concurrent_trust_writes_do_not_lose_entries` runs eight
threads and verifies all entries survive a reload. The lock-held write is
also verified by code inspection because the stale-snapshot property is not
directly observable from the public API.

### F-03 (Medium) Ratchet forward-skip desync

Root cause: senders advance their outgoing chain after every attempted send,
including failed or cancelled OPP attempts. Receivers can therefore see a
container at a step several positions ahead. The old receiver returned the
container's step and the commit function expected the current step, so any
legitimate skip failed the commit and the container was deleted. The chain
then stayed at the old position and every later file failed too.

Impact: availability/functionality loss for paired transfers, remotely
triggerable by causing a cancelled or failed send. No confidentiality or
signature bypass.

Fix: `PeerDecrypted` carries `from_step` (the receiver's current step) and
`next_step` (the step to store after authentication). `commit_incoming`
checks `from_step` is still current, requires forward movement, and stores
`next_step`. All Linux and Windows call sites pass both values. The bound is
kept consistent with `PeerDecryptor::decrypt_to_gated`.

Tests: `crypto::tests::peer_containers_can_skip_failed_send_steps`,
`trust::tests::incoming_ratchet_accepts_forward_skips_and_rejects_rewinds`,
plus the pre-existing peer round-trip and replay tests.

### F-04 (Medium) Blocklist refresh eviction

Root cause: refresh merged the fresh feed first and then added older cached
hashes only into the remaining room. A feed that filled the cap could push
out hashes the machine already knew, including bundled detections.

Impact: a compromised or oversized feed endpoint could remove detection of a
sample the machine previously blocked. This is defense evasion, not host
compromise by itself.

Fix: `merge_fresh` starts from the bundled baseline plus the previous list,
keeps all known hashes, and only adds fresh hashes into the remaining room
(`src/security.rs::refresh`). A second-review edge where the bundled baseline
pushed the list a few entries over the cap was also fixed so the overflow is
bounded and never evicts known entries.

Test: `security::tests::merge_fresh_keeps_history_and_respects_the_cap`.

### F-05 (Medium) Pairing state exhaustion and replacement

Root cause: incoming pairing requests bypass the file prompt by design. The
pending map was unbounded, cleanup ran only on request objects, and a second
request from the same address could replace an in-flight handshake.

Impact: an unauthenticated nearby device could allocate pending state for
many spoofed addresses (bounded only by the 3-minute timeout) or disrupt a
legitimate pairing attempt.

Fix: `MAX_PENDING_PAIRINGS = 32`, cleanup before every object, a duplicate
request from an address with pending incoming state is refused, and the
capacity/duplicate checks are repeated under the lock after the expensive
SPAKE2 step (`src/identity.rs::PairingManager::handle_bytes`).

Tests: `identity::tests::pending_pairing_requests_are_bounded`,
`identity::tests::a_second_request_cannot_replace_an_in_flight_handshake`.

### F-06 (Medium) Unbounded pairing replies

Root cause: a valid pairing request causes the receiver to open a fresh OPP
send for the response/confirmation. Linux spawned a detached task and Windows
spawned a thread for every request, with no limit.

Impact: a control-object flood could exhaust tasks, sockets, or thread
stacks. Unauthenticated peers can create structurally valid SPAKE2 requests.

Fix: a four-permit semaphore (`PAIRING_REPLY_SLOTS`) on Linux and a
four-worker atomic guard (`PAIRING_REPLY_THREADS`) on Windows. When full, the
reply is skipped with a UI log entry and pairing can be retried.

Verification: code inspection plus Windows cross-target Clippy; no direct
runtime test because the reply path performs a real OPP send.

### F-07 (Medium) Linux authorization-wait accounting

Root cause: the concurrency check counted only transfers already registered
in the pending map. Requests waiting for an Allow/Decline decision were not
counted, so many unknown senders could hold authorization prompts without
consuming a slot.

Impact: remote resource/prompt exhaustion and starvation of legitimate
transfers.

Fix: `reserve_capacity` counts registered entries plus reservations, and a
RAII `CapacityReservation` covers the whole authorization window, including
every early error path. The reservation is released under the pending lock
when the entry is registered.

Test: `agent::tests::waiting_authorizations_count_toward_the_incoming_limit`.

### F-08 (Medium) Windows thread-per-connection

Root cause: the RFCOMM `ConnectionReceived` handler spawned a worker thread
and only then tried to acquire an `IncomingSlot`. Rejected connections still
created a thread.

Impact: a nearby device opening connections quickly could consume thread
stacks and scheduler capacity even though the transfer limit was four.

Fix: the slot is acquired in the event handler before `std::thread::spawn`,
and moved into the worker as a guard (`src/win/receiver.rs::advertise`).

Verification: Windows cross-target Clippy and inspection; runtime validation
needs Windows hardware.

### F-09 (Low) Sender-side downgrade with a damaged chain

Root cause: `platform::send` selected per-device encryption only when
`trust.is_paired` was true, which requires both ratchet directions. A pinned
entry with a missing/corrupt incoming chain was treated as unpaired and could
fall back to plaintext or the shared passphrase.

Impact: with a damaged trust entry, content could be sent in a weaker mode
addressed to a pinned device. The receiving side would reject it, but an
impersonator at that address might read it.

Fix: selection uses `is_pinned` and requires a usable outgoing chain;
otherwise the send is refused with an instruction to pair again
(`src/platform.rs::send`). No send-backend integration test exists; the
semantics are covered by the `is_pinned` test above.

### F-10 (Medium) Windows roaming identity and shared staging

Root cause: `config_dir()` used `FOLDERID_RoamingAppData`, and incoming
staging used `%TEMP%\kalo\staging`.

Impact: a roaming profile could copy the Ed25519 private identity and ratchet
state to another machine, weakening device binding and risking step reuse.
A redirected or shared TEMP could expose staged plaintext or let another
account pre-create the staging path.

Fix: Windows config now uses `FOLDERID_LocalAppData`/`LOCALAPPDATA`, and
Windows staging lives under the private config directory
(`src/paths.rs`, `src/win/receiver.rs::staging_root`). `README.md` was
updated to say “local application data”.

Verification: code inspection and cross-target Clippy. Windows runtime
validation is still required.

### F-11 (Low) Shared temporary staging

Root cause: outgoing containers and pairing objects were created under
`/tmp/kalo/...` on Unix.

Impact: another local user could pre-create or tamper with the directory,
causing failed sends or pairing, or could race the ciphertext file. The
content is encrypted and pairing objects contain no passphrase, so this is
local tampering/DoS rather than remote confidentiality loss.

Fix: both use `paths::config_dir()` (`outgoing`/`pairing`), created 0700 with
random 0600 files (`src/crypto.rs::TempContainer::new`,
`src/identity.rs::PairingFile::new`).

Verification: `identity::tests::pairing_files_are_private_and_removed_on_drop`
and inspection of the container staging path.

### F-12 (Low) Received-file permission window

Root cause: the hard-link move inherited the staging file's mode, and the
cross-device copy created the destination with the process umask; hardening
ran only after the move.

Impact: on a multi-user Unix machine, a received file could be readable by
other users for a short window, or longer if the later hardening failed.

Fix: `move_file` sets the source to 0600 before linking, and
`copy_no_replace` creates the destination with mode 0600 from the first byte
(`src/sanitize.rs`).

Tests: `sanitize::tests::move_file_tightens_permissions_before_linking`,
`sanitize::tests::copy_fallback_creates_owner_only_files`.

### F-13 (Low) Settings temp-file creation

Root cause: `write_json` used `File::create`, which follows an existing
symlink/truncates an existing file, and relied on a later chmod. The parent
directory is already 0700 and the name contains a random UUID, so the
practical window is small.

Impact: a local race could expose the fallback plaintext passphrase or
replace the intended temp file.

Fix: `create_new(true)` plus `mode(0o600)` at creation on Unix
(`src/settings.rs::write_json`), with the random name and atomic rename kept.

Test: `settings::tests::settings_files_are_owner_only`.

### F-14 (Low) Bidi and zero-width filename/label spoofing

Root cause: `char::is_control` does not remove Unicode bidi overrides, zero
width characters, or line/paragraph separators. A received name such as
`photo\u{202E}gnp.exe` can render as a different extension, and invisible
characters can hide a dot.

Impact: user deception in the file list/UI and in the saved name; Kalo
itself never executes content.

Fix: `sanitize::is_format_control` strips these code points in `filename`,
and `strip_unsafe_text` is shared by `identity::clean_name` for peer labels.
Tests:
`sanitize::tests::filename_strips_bidi_and_invisible_formatting`.

### F-15 (Low) Windows peer-name sanitization

Root cause: `remote_name` returned the WinRT display/raw name without
removing control or bidi characters.

Impact: log/UI spoofing and misleading sender-folder labels on Windows.

Fix: `remote_name` runs `sanitize::strip_unsafe_text` and trims the result
(`src/win/receiver.rs`). The shared sanitizer has unit coverage; Windows
runtime behavior still needs hardware validation.

### F-16 (Low) Filename length invariant

Root cause: after truncating to 200 bytes, the code could prepend `_` to
neutralize a reserved DOS name, producing 201 bytes.

Impact: an internal invariant was broken. No direct exploit was found: the
result is still below common 255-byte filesystem limits, but downstream code
and tests assume the cap.

Fix: `truncate_name` is applied again after the prefix, including the
trailing-dot/space cleanup (`src/sanitize.rs::filename`). The issue was found
by `fuzz/filename`; the target was rerun clean after the fix.

Test: `sanitize::tests::reserved_name_prefix_cannot_exceed_the_length_cap`.

### F-17 (Low) Ratchet maximum-skip boundary

Root cause: `PeerDecryptor` accepted a container exactly `MAX_CHAIN_SKIP`
steps ahead, but `commit_incoming` compared the one-past step against the
same limit and rejected it. The container decrypted, then its plaintext was
deleted and the receiver stayed stuck.

Impact: an edge-case availability failure after exactly 4096 skipped steps.

Fix: `commit_incoming` allows `MAX_CHAIN_SKIP + 1` advancement, with the
boundary documented and tied to the decryptor.
Tests: `crypto::tests::peer_container_at_the_maximum_skip_reports_a_committable_next_step`
and the boundary branch in `trust::tests::incoming_ratchet_accepts_forward_skips_and_rejects_rewinds`.

### F-18 (Informational) CI supply chain and advisory scanning

Root cause/observation: workflow actions were referenced by movable tags, and
CI had no dependency-advisory job.

Impact: a compromised or retargeted action tag could run with repository
permissions; vulnerable dependencies would not fail CI.

Fix: all actions are pinned to full commit SHAs, and a `security` job installs
pinned `cargo-audit 0.23.0` and runs `cargo audit`
(`.github/workflows/ci.yml`). The release job depends on the new job. YAML was
validated with Python's `yaml.safe_load`.

Residual: SHA pinning does not provide artifact signing or SLSA provenance.

## 5. Validation evidence

Environment: Linux 7.0.0-43-generic, rustc/cargo 1.98.1, cargo-audit 0.23.0,
Windows GNU cross toolchain from LLVM-MinGW.

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test --all-targets` | 143 passed, 0 failed |
| `cargo build --release --locked` | success |
| Windows GNU cross Clippy (all targets, `-D warnings`) | clean |
| `cargo-audit audit` | 0 vulnerabilities, 6 warnings, exit 0 |
| `cargo +nightly fuzz run obex_parser -- -max_total_time=45 -rss_limit_mb=2048` | 2,797,503 runs, no crash |
| `cargo +nightly fuzz run filename -- -max_total_time=60 -rss_limit_mb=2048` | 5,363,232 runs, no crash |
| Python `yaml.safe_load` on `.github/workflows/ci.yml` | valid; jobs `linux, windows, macos, fuzz, security, arch, release` |
| repository secret patterns (`BEGIN ... PRIVATE KEY`, AWS/GitHub/Slack tokens, password/secret/api-key assignments) | no matches |

The filename fuzz target found F-16 during the audit; the run above is after
the fix. The OBEX target exercises truncated/inconsistent frames and length
handling in the shared parser.

### Dependency advisories

`cargo audit` reported no vulnerabilities. It reported six warnings:

| Crate | Version | Warning | Advisory |
| --- | --- | --- | --- |
| paste | 1.0.15 | unmaintained | RUSTSEC-2024-0436 |
| ttf-parser | 0.25.1 | unmaintained | RUSTSEC-2026-0192 |
| zbus_names | 4.3.5 | unmaintained | RUSTSEC-2026-0371 |
| zvariant | 5.15.1 | unmaintained | RUSTSEC-2026-0370 |
| zvariant_derive | 5.15.1 | unmaintained | RUSTSEC-2026-0372 |
| lru | 0.16.4 | unsound | RUSTSEC-2026-0253 |

`lru 0.16.4` is reached through `iced_wgpu 0.14` -> `cryoglyph 0.1.0`. The
advisory recommends `lru >= 0.18.2`, but `cryoglyph 0.1.0` pins the 0.16
major line and no newer `cryoglyph` release exists. A forced major-version
override would be an unsupported dependency change, so it was not applied.
Kalo does not call `lru` directly; the exposed path is iced's internal cache.

## 6. Residual risks

- The six advisories above remain. Five are “unmaintained”, not known
  vulnerabilities; `lru` is unsound in `LruCache::pop()` under panic, with no
  compatible patched release available.
- macOS could not be type-checked locally because the Darwin SDK/C headers
  needed by `ring` are absent. CI builds macOS, and macOS cannot receive OPP
  by design, so the pairing receiver limitation remains.
- Windows audit changes were cross-compiled and linted, not exercised on
  physical Windows 10/11 hardware.
- Bluetooth/RFCOMM behavior against real phones, two-adapter concurrency, and
  stack-specific disconnects were not tested. The OBEX parser was fuzzed in
  isolation.
- The malware blocklist is a hash list, not a full antivirus. Unknown malware
  is not detected; a compromised feed is bounded but can still add false
  positives. Mark-of-the-Web is advisory and unavailable on some filesystems.
- Pairing relies on the strength of the shared passphrase. SPAKE2 prevents
  passive recovery and the pending cap bounds online state, but there is no
  per-address rate limiter beyond the global cap and timeout.
- Bluetooth addresses are not authenticated by the stack. Pairing blocks
  downgrade from a pinned address, but an attacker can still cause
  unauthenticated connection/prompt noise and denial of service.
- A local attacker who can write the user's private config can alter trust,
  settings, or the identity file. File modes are 0600/0700, but local account
  compromise is out of scope.
- Linux incoming staging is under the obexd session root. Kalo creates private
  subdirectories and files, but the permissions of that root are controlled by
  obexd/the session.
- Release artifacts are built by CI from `main`; actions are SHA-pinned, but
  there is no artifact signing or independent provenance verification.
- Fuzzing is time-boxed in CI and in this audit; it is not exhaustive.
- `cargo-deny` and Semgrep were unavailable and were not run.
- New advisories can be published after this audit. The CI job will fail on a
  future vulnerability, but the audit result is a snapshot.

## 7. Conclusion

All eighteen confirmed findings have a code fix and, where practical, a
regression test in the working tree. Two High findings affected paired-device
authentication and persisted trust integrity; both are closed by the changes
above. The remaining risks are documented rather than hidden. The project
should be re-audited after dependency updates, before a stable release, and
after any change to pairing, trust persistence, or the receive pipeline.
